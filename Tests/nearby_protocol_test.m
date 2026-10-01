// Compiled on macOS together with the actual parser extracted from the app.
#import <Foundation/Foundation.h>
#include <assert.h>
static NSData *encode(id obj) { return [NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingFragmentsAllowed error:nil]; }
int main(void) {
 @autoreleasepool {
  NSDictionary *valid = @{@"v":@1,@"id":@"00000000-0000-4000-8000-000000000001",@"type":@"request",@"action":@"status",@"bundle":@"Vodafone_hu",@"sim":@0};
  assert(CSDecode(encode(valid)));
  for (NSString *action in @[@"status",@"apply",@"restore"]) { NSMutableDictionary *v=valid.mutableCopy; v[@"action"]=action; assert(CSDecode(encode(v))); }
  for (NSString *action in @[@"recover",@"shell",@"write_file",@""]) { NSMutableDictionary *v=valid.mutableCopy; v[@"action"]=action; assert(!CSDecode(encode(v))); }
  for (id bundle in @[@"../Library",@"A.bundle",@"",@"A B",@"A/B",@"A\\B",@"Профиль",@42,NSNull.null]) { NSMutableDictionary *v=valid.mutableCopy; v[@"bundle"]=bundle; assert(!CSDecode(encode(v))); }
  for (id sim in @[@(-1),@3,@YES,@0.5,@"0",NSNull.null]) { NSMutableDictionary *v=valid.mutableCopy; v[@"sim"]=sim; assert(!CSDecode(encode(v))); }
  for (id version in @[@0,@2,@YES,@"1",@1.5,NSNull.null]) { NSMutableDictionary *v=valid.mutableCopy; v[@"v"]=version; assert(!CSDecode(encode(v))); }
  NSMutableDictionary *bad=valid.mutableCopy; bad[@"path"]=@"/var/mobile"; assert(!CSDecode(encode(bad)));
  bad=valid.mutableCopy; bad[@"id"]=@"not-a-uuid"; assert(!CSDecode(encode(bad)));
  bad=valid.mutableCopy; [bad removeObjectForKey:@"bundle"]; assert(!CSDecode(encode(bad)));
  assert(!CSDecode([NSMutableData dataWithLength:4097]));
  assert(!CSDecode([@"[" dataUsingEncoding:NSUTF8StringEncoding]));
  assert(!CSDecode(encode(@[]))); assert(!CSDecode(encode(NSNull.null)));
  NSDictionary *reply=@{@"v":@1,@"id":valid[@"id"],@"type":@"result",@"state":@"done",@"catalog":@YES,@"confirmed":@NO,@"recovery":@NO,@"sims":@2};
  assert(CSDecode(encode(reply)));
  bad=reply.mutableCopy; bad[@"private_key"]=@"not allowed"; assert(!CSDecode(encode(bad)));
  bad=reply.mutableCopy; bad[@"catalog"]=@"yes"; assert(!CSDecode(encode(bad)));
  bad=reply.mutableCopy; bad[@"sims"]=@9; assert(!CSDecode(encode(bad)));
  puts("Nearby parser positive/negative cases passed. This is not a device or network test.");
 }
 return 0;
}
